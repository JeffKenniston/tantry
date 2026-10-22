#![allow(dead_code)]
use dashmap::DashMap;
use crate::error::IamError;
use uuid::Uuid;
use chrono::Utc;

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

    pub fn issue_grant(&self, ttl_secs: i64, normalized_service: &str) -> Result<ScopedTunnelGrant, IamError> {
        let ttl_secs = ttl_secs.clamp(1, 3600);
        let grant_id = Uuid::now_v7().to_string();
        let expires_at_ms = Utc::now().timestamp_millis() + (ttl_secs * 1000);

        let grant = ScopedTunnelGrant {
            grant_id: grant_id.clone(),
            spiffe_id: "spiffe://local/stub".to_string(),
            service_name: normalized_service.to_string(),
            expires_at_ms,
            token: format!("jwt_stub_for_{}", normalized_service),
        };

        self.by_id.insert(grant_id.clone(), grant.clone());
        let mut entry = self.by_service.entry(normalized_service.to_string()).or_default();
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

    pub fn verify_token(&self, _token: &str, _verifier: &dyn crate::IdentityManager, now_ms: i64) -> Result<ScopedTunnelGrant, IamError> {
        let grant_id = "stub_extract_jti".to_string();
        if let Some(grant) = self.by_id.get(&grant_id) {
            if now_ms >= grant.expires_at_ms {
                 // evict
                 self.by_id.remove(&grant_id);
                 return Err(IamError::NotImplemented);
            }
            return Ok(grant.clone());
        }
        Err(IamError::NotImplemented)
    }
}
