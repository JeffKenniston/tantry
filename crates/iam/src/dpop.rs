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
