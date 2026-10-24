#![allow(dead_code)]
use crate::error::IamError;
use crate::svid::{JwtSvidClaims, WorkloadSvid, mint_hybrid_jwt_svid};
use base64::Engine as _;
use chrono::Utc;
use dashmap::DashMap;
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct ScopedTunnelGrant {
    pub grant_id: String,
    pub spiffe_id: String,
    pub service_name: String,
    pub expires_at_ms: i64,
    pub token: String,
}

pub struct ScopedTunnelRegistry {
    by_id: DashMap<String, ScopedTunnelGrant>,
    by_service: DashMap<String, Vec<String>>,
}

impl ScopedTunnelRegistry {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            by_id: DashMap::new(),
            by_service: DashMap::new(),
        }
    }

    pub fn normalize_host(raw: &str) -> String {
        let mut normalized = raw;
        if let Some(pos) = normalized.find("://") {
            normalized = &normalized[(pos + 3)..];
        }
        if let Some(pos) = normalized.find('/') {
            normalized = &normalized[..pos];
        }
        if let Some(pos) = normalized.find(':') {
            normalized = &normalized[..pos];
        }
        normalized.to_string()
    }

    pub fn issue_grant(
        &self,
        ttl_secs: i64,
        normalized_service: &str,
        svid: &WorkloadSvid,
    ) -> Result<ScopedTunnelGrant, IamError> {
        let ttl_secs = ttl_secs.clamp(1, 3600);
        let grant_id = Uuid::now_v7().to_string();

        let now = Utc::now().timestamp();
        let iat = now;
        let exp = now + ttl_secs;

        let pq_pk_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(&svid.mldsa65_verifying_key_bytes);

        let claims = JwtSvidClaims {
            iss: svid.spiffe_id.uri().to_string(),
            sub: svid.spiffe_id.uri().to_string(),
            aud: vec![format!("tunnel://{}", normalized_service)],
            exp,
            iat,
            jti: grant_id.clone(),
            pq_pk_b64,
        };

        let token = mint_hybrid_jwt_svid(svid, &claims)?;

        let expires_at_ms = Utc::now().timestamp_millis() + (ttl_secs * 1000);
        let grant = ScopedTunnelGrant {
            grant_id: grant_id.clone(),
            spiffe_id: svid.spiffe_id.uri().to_string(),
            service_name: normalized_service.to_string(),
            expires_at_ms,
            token,
        };

        self.by_id.insert(grant_id.clone(), grant.clone());
        let mut entry = self
            .by_service
            .entry(normalized_service.to_string())
            .or_default();
        entry.push(grant_id);

        Ok(grant)
    }

    pub fn is_service_active(&self, host_or_authority: &str, now_ms: i64) -> bool {
        let normalized = Self::normalize_host(host_or_authority);
        if let Some(mut grants) = self.by_service.get_mut(&normalized) {
            grants.retain(|id| {
                if let Some(grant) = self.by_id.get(id) {
                    grant.expires_at_ms > now_ms
                } else {
                    false
                }
            });
            !grants.is_empty()
        } else {
            false
        }
    }

    pub fn verify_token(
        &self,
        token: &str,
        verifier: &dyn crate::IdentityManager,
        now_ms: i64,
    ) -> Result<ScopedTunnelGrant, IamError> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(IamError::TunnelGrantExpiredOrInvalid(
                "Invalid JWT format".to_string(),
            ));
        }

        let claims_b64 = parts[1];
        let claims_json_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(claims_b64)
            .map_err(|_| {
                IamError::TunnelGrantExpiredOrInvalid("Invalid claims base64".to_string())
            })?;
        let claims: JwtSvidClaims = serde_json::from_slice(&claims_json_bytes).map_err(|_| {
            IamError::TunnelGrantExpiredOrInvalid("Invalid claims JSON".to_string())
        })?;

        let grant_id = claims.jti;

        let expected_aud = {
            let grant = self.by_id.get(&grant_id).ok_or_else(|| {
                IamError::TunnelGrantExpiredOrInvalid("Token not found in registry".to_string())
            })?;
            format!("tunnel://{}", grant.service_name)
        };
        verifier.verify_jwt_svid(token, &expected_aud)?;

        if let Some(grant) = self.by_id.get(&grant_id) {
            if now_ms >= grant.expires_at_ms {
                drop(grant); // explicit drop before mutating map
                self.by_id.remove(&grant_id);
                return Err(IamError::TunnelGrantExpiredOrInvalid(
                    "Token expired".to_string(),
                ));
            }
            return Ok(grant.clone());
        }
        Err(IamError::TunnelGrantExpiredOrInvalid(
            "Token not found in registry".to_string(),
        ))
    }
}
