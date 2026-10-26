use dashmap::DashMap;
use chrono::Utc;
use crate::spiffe::SpiffeId;
use crate::error::IamError;
use crate::svid::{WorkloadSvid, mint_hybrid_jwt_svid, verify_hybrid_jwt_svid};
use std::sync::Arc;

pub struct ScopedTunnelGrant {
    pub grant_id: String,
    pub spiffe_id: SpiffeId,
    pub service_name: String,
    pub expires_at_ms: i64,
    pub token: String,
}

pub struct ScopedTunnelRegistry {
    pub by_id: DashMap<String, Arc<ScopedTunnelGrant>>,
    pub by_service: DashMap<String, Vec<String>>,
}

impl ScopedTunnelRegistry {
    pub fn new() -> Self {
        Self {
            by_id: DashMap::new(),
            by_service: DashMap::new(),
        }
    }

    pub fn normalize_host(raw: &str) -> String {
        let mut host = raw;
        if let Some(pos) = host.find("://") {
            host = &host[pos + 3..];
        }
        if let Some(pos) = host.find('/') {
            host = &host[..pos];
        }
        if let Some(pos) = host.find(':') {
            host = &host[..pos];
        }
        host.to_lowercase()
    }

    pub fn issue_grant(&self, svid: &WorkloadSvid, service: &str, ttl_secs: i64) -> Result<Arc<ScopedTunnelGrant>, IamError> {
        let ttl_secs = ttl_secs.clamp(1, 3600);
        let normalized_service = Self::normalize_host(service);

        let token = mint_hybrid_jwt_svid(
            svid,
            vec![format!("tunnel://{}", normalized_service)]
        )?;

        // Temporarily decode token to get the jti (which is the grant_id)
        let parts: Vec<&str> = token.split('.').collect();
        let claims_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            parts[1]
        ).unwrap();
        let claims: serde_json::Value = serde_json::from_slice(&claims_bytes).unwrap();
        let grant_id = claims["jti"].as_str().unwrap().to_string();

        let expires_at_ms = Utc::now().timestamp_millis() + (ttl_secs * 1000);

        let grant = Arc::new(ScopedTunnelGrant {
            grant_id: grant_id.clone(),
            spiffe_id: svid.spiffe_id.clone(),
            service_name: normalized_service.clone(),
            expires_at_ms,
            token,
        });

        self.by_id.insert(grant_id.clone(), grant.clone());

        self.by_service.entry(normalized_service)
            .or_insert_with(Vec::new)
            .push(grant_id);

        Ok(grant)
    }

    pub fn verify_token(&self, token: &str, ed25519_pk: &[u8; 32], mldsa65_pk: &[u8], expected_aud: &str, require_pq: bool) -> Result<Arc<ScopedTunnelGrant>, IamError> {
        let claims = verify_hybrid_jwt_svid(token, ed25519_pk, mldsa65_pk, expected_aud, require_pq)?;

        let grant = self.by_id.get(&claims.jti)
            .ok_or_else(|| IamError::TunnelGrantExpiredOrInvalid("Token not found in registry".to_string()))?;

        let now_ms = Utc::now().timestamp_millis();
        if now_ms >= grant.expires_at_ms {
            drop(grant);
            self.by_id.remove(&claims.jti);
            return Err(IamError::TunnelGrantExpiredOrInvalid("Token expired in registry".to_string()));
        }

        Ok(grant.value().clone())
    }

    pub fn is_service_active(&self, service: &str) -> bool {
        let normalized = Self::normalize_host(service);
        let now_ms = Utc::now().timestamp_millis();

        if let Some(mut grants) = self.by_service.get_mut(&normalized) {
            let _initial_len = grants.len();
            grants.retain(|id| {
                if let Some(grant) = self.by_id.get(id) {
                    if now_ms < grant.expires_at_ms {
                        return true;
                    } else {
                        // Expired
                    }
                }
                false
            });

            !grants.is_empty()
        } else {
            false
        }
    }
}
