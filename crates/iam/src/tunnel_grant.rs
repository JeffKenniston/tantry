#![allow(dead_code)]
use crate::error::IamError;
use dashmap::DashMap;
use zeroize::Zeroizing;
use ed25519_dalek::{SigningKey, Signer, Verifier, Signature};
use rand_core::RngCore;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ScopedTunnelGrant {
    pub expires_at_ms: i64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ScopedTunnelToken {
    pub service_name: String,
    pub expires_at_ms: i64,
    pub signature: Vec<u8>,
}

pub struct ScopedTunnelRegistry {
    pub grants: DashMap<String, ScopedTunnelGrant>,
    pub signing_key: Zeroizing<[u8; 32]>,
    pub verifying_key: [u8; 32],
}

pub fn normalize_service_authority(raw: &str) -> Result<String, IamError> {
    let mut normalized = raw.trim();
    if let Some(rest) = normalized.strip_prefix("https://") {
        normalized = rest;
    } else if let Some(rest) = normalized.strip_prefix("http://") {
        normalized = rest;
    } else if let Some(rest) = normalized.strip_prefix("tunnel://") {
        normalized = rest;
    }

    if let Some(pos) = normalized.find('/') {
        normalized = &normalized[..pos];
    }
    if let Some(pos) = normalized.find(':') {
        normalized = &normalized[..pos];
    }

    normalized = normalized.trim();
    let lower = normalized.to_lowercase();

    if lower.is_empty() {
        return Err(IamError::TunnelGrantExpiredOrInvalid("Empty service name".to_string()));
    }

    for b in lower.bytes() {
        if !b.is_ascii_alphanumeric() && b != b'-' && b != b'.' && b != b'_' && b != b'~' {
            return Err(IamError::TunnelGrantExpiredOrInvalid("Invalid character in service name".to_string()));
        }
    }
    Ok(lower)
}

impl ScopedTunnelRegistry {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let mut seed = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut seed);
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key().to_bytes();
        Self {
            grants: DashMap::new(),
            signing_key: Zeroizing::new(signing_key.to_bytes()),
            verifying_key,
        }
    }

    pub fn request_scoped_tunnel_token(&self, service_name: &str, ttl_secs: u64, now_ms: i64) -> Result<ScopedTunnelToken, IamError> {
        let norm_service = normalize_service_authority(service_name)?;
        let grant_uri = format!("tunnel://{}", norm_service);
        let expires_at_ms = now_ms + (ttl_secs.min(3600) as i64) * 1000;

        let mut hasher = blake3::Hasher::new();
        hasher.update(b"tantry:tunnel-grant:v3");
        hasher.update(grant_uri.as_bytes());
        hasher.update(&expires_at_ms.to_be_bytes());
        let digest = hasher.finalize();

        let mut arr = [0u8; 32];
        arr.copy_from_slice(self.signing_key.as_ref());
        let signing_key = SigningKey::from_bytes(&arr);
        let signature = signing_key.sign(digest.as_bytes()).to_bytes().to_vec();

        self.grants.insert(norm_service.clone(), ScopedTunnelGrant { expires_at_ms });

        Ok(ScopedTunnelToken {
            service_name: norm_service,
            expires_at_ms,
            signature,
        })
    }

    pub fn verify_scoped_tunnel_token(&self, token: &ScopedTunnelToken, now_ms: i64) -> Result<(), IamError> {
        if now_ms > token.expires_at_ms {
            return Err(IamError::TunnelGrantExpiredOrInvalid("Token expired".to_string()));
        }

        let grant_uri = format!("tunnel://{}", token.service_name);
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"tantry:tunnel-grant:v3");
        hasher.update(grant_uri.as_bytes());
        hasher.update(&token.expires_at_ms.to_be_bytes());
        let digest = hasher.finalize();

        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&self.verifying_key)
            .map_err(|_| IamError::Ed25519VerificationFailed)?;

        let sig = Signature::from_slice(&token.signature)
            .map_err(|_| IamError::TunnelGrantExpiredOrInvalid("Invalid signature length".to_string()))?;
        verifying_key.verify(digest.as_bytes(), &sig)
            .map_err(|_| IamError::TunnelGrantExpiredOrInvalid("Invalid signature".to_string()))?;

        #[allow(clippy::collapsible_if)]
        if let Some(grant) = self.grants.get(&token.service_name) {
            if now_ms <= grant.expires_at_ms {
                return Ok(());
            }
        }

        Err(IamError::TunnelGrantExpiredOrInvalid("Grant not found or expired".to_string()))
    }

    pub fn is_service_active(&self, host_or_authority: &str, now_ms: i64) -> bool {
        let norm = match normalize_service_authority(host_or_authority) {
            Ok(n) => n,
            Err(_) => return false,
        };
        #[allow(clippy::collapsible_if)]
        if let Some(grant) = self.grants.get(&norm) {
            if now_ms <= grant.expires_at_ms {
                return true;
            }
        }
        self.grants.remove(&norm);
        false
    }
}
