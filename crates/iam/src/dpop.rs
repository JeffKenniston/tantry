use crate::error::IamError;
use crate::svid::WorkloadSvid;
use chrono::Utc;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey, };
use ed25519_dalek::pkcs8::DecodePrivateKey;
use serde_json::json;

pub fn mint_dpop_proof(svid: &WorkloadSvid, htm: &str, htu: &str, access_token: Option<&str>) -> Result<String, IamError> {
    let normalized_htu = if let Some(pos) = htu.find('?') {
        &htu[..pos]
    } else if let Some(pos) = htu.find('#') {
        &htu[..pos]
    } else {
        htu
    };

    let jti = Uuid::now_v7().to_string();
    let iat = Utc::now().timestamp();
    let htm = htm.to_uppercase();

    let ath = access_token.map(|t| {
        let mut hasher = Sha256::new();
        hasher.update(t.as_bytes());
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize())
    });

    let ed25519_pk_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(svid.ed25519_public_key);
    let header = json!({
        "typ": "dpop+jwt",
        "alg": "EdDSA",
        "jwk": {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": ed25519_pk_b64
        }
    });

    let mut payload_map = serde_json::Map::new();
    payload_map.insert("jti".to_string(), json!(jti));
    payload_map.insert("htm".to_string(), json!(htm));
    payload_map.insert("htu".to_string(), json!(normalized_htu));
    payload_map.insert("iat".to_string(), json!(iat));
    if let Some(a) = ath {
        payload_map.insert("ath".to_string(), json!(a));
    }
    let payload = serde_json::Value::Object(payload_map);

    let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_string(&header).unwrap().as_bytes());
    let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload).unwrap().as_bytes());

    let message = format!("{}.{}", header_b64, payload_b64);

    let sk = SigningKey::from_pkcs8_der(svid.ed25519_pkcs8_der.as_ref())
        .map_err(|e| IamError::CertificateGenerationError(e.to_string()))?;

    let signature = sk.sign(message.as_bytes());
    let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature.to_bytes());

    Ok(format!("{}.{}.{}", header_b64, payload_b64, sig_b64))
}

use ed25519_dalek::{Verifier, VerifyingKey, Signature};

pub fn verify_dpop_proof(
    proof: &str,
    htm: &str,
    htu: &str,
    access_token: Option<&str>,
    replay_cache: &dashmap::DashMap<String, i64>,
) -> Result<(), IamError> {
    let parts: Vec<&str> = proof.split('.').collect();
    if parts.len() != 3 {
        return Err(IamError::DpopValidationFailed("Invalid DPoP proof format".to_string()));
    }

    let header_b64 = parts[0];
    let payload_b64 = parts[1];
    let sig_b64 = parts[2];

    let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(header_b64)
        .map_err(|_| IamError::DpopValidationFailed("Invalid header base64".to_string()))?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|_| IamError::DpopValidationFailed("Invalid header JSON".to_string()))?;

    if header.get("typ").and_then(|v| v.as_str()) != Some("dpop+jwt") {
        return Err(IamError::DpopValidationFailed("Invalid typ".to_string()));
    }

    let jwk = header.get("jwk").ok_or_else(|| IamError::DpopValidationFailed("Missing jwk".to_string()))?;
    let crv = jwk.get("crv").and_then(|v| v.as_str());
    if crv != Some("Ed25519") {
        return Err(IamError::DpopValidationFailed("Unsupported crv".to_string()));
    }

    let x_b64 = jwk.get("x").and_then(|v| v.as_str()).ok_or_else(|| IamError::DpopValidationFailed("Missing x in jwk".to_string()))?;
    let x_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(x_b64)
        .map_err(|_| IamError::DpopValidationFailed("Invalid x base64".to_string()))?;

    let mut ed25519_pk = [0u8; 32];
    if x_bytes.len() != 32 {
        return Err(IamError::DpopValidationFailed("Invalid Ed25519 public key length".to_string()));
    }
    ed25519_pk.copy_from_slice(&x_bytes);

    let message = format!("{}.{}", header_b64, payload_b64);
    let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(sig_b64)
        .map_err(|_| IamError::DpopValidationFailed("Invalid signature base64".to_string()))?;
    let ed_sig = Signature::from_slice(&sig_bytes)
        .map_err(|_| IamError::DpopValidationFailed("Invalid Ed25519 signature".to_string()))?;
    let ed_vk = VerifyingKey::from_bytes(&ed25519_pk)
        .map_err(|_| IamError::DpopValidationFailed("Invalid Ed25519 public key".to_string()))?;

    ed_vk.verify(message.as_bytes(), &ed_sig)
        .map_err(|_| IamError::DpopValidationFailed("Signature verification failed".to_string()))?;

    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload_b64)
        .map_err(|_| IamError::DpopValidationFailed("Invalid payload base64".to_string()))?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .map_err(|_| IamError::DpopValidationFailed("Invalid payload JSON".to_string()))?;

    let now = Utc::now().timestamp();
    let iat = payload.get("iat").and_then(|v| v.as_i64()).ok_or_else(|| IamError::DpopValidationFailed("Missing iat".to_string()))?;
    if (now - iat).abs() > 60 {
        return Err(IamError::DpopValidationFailed("iat out of range".to_string()));
    }

    let htm_payload = payload.get("htm").and_then(|v| v.as_str()).ok_or_else(|| IamError::DpopValidationFailed("Missing htm".to_string()))?;
    if htm_payload != htm.to_uppercase() {
        return Err(IamError::DpopValidationFailed("htm mismatch".to_string()));
    }

    let htu_payload = payload.get("htu").and_then(|v| v.as_str()).ok_or_else(|| IamError::DpopValidationFailed("Missing htu".to_string()))?;
    let normalized_htu = if let Some(pos) = htu.find('?') {
        &htu[..pos]
    } else if let Some(pos) = htu.find('#') {
        &htu[..pos]
    } else {
        htu
    };
    if htu_payload != normalized_htu {
        return Err(IamError::DpopValidationFailed("htu mismatch".to_string()));
    }

    if let Some(at) = access_token {
        let ath_payload = payload.get("ath").and_then(|v| v.as_str()).ok_or_else(|| IamError::DpopValidationFailed("Missing ath".to_string()))?;
        let mut hasher = Sha256::new();
        hasher.update(at.as_bytes());
        let expected_ath = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize());
        if ath_payload != expected_ath {
            return Err(IamError::DpopValidationFailed("ath mismatch".to_string()));
        }
    }

    let jti = payload.get("jti").and_then(|v| v.as_str()).ok_or_else(|| IamError::DpopValidationFailed("Missing jti".to_string()))?;
    if replay_cache.insert(jti.to_string(), now).is_some() {
        return Err(IamError::DpopReplayDetected(jti.to_string()));
    }

    Ok(())
}
