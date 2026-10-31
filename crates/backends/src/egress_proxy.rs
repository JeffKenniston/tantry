use crate::error::BackendError;

// Actual ScopedTunnelRegistry is in iam crate.
// Here we use it.
use data::audit_mmr::AuditMmrStore;
use iam::tunnel_grant::ScopedTunnelRegistry;

/// Egress Proxy for Transparent TLS SNI & HTTP CONNECT
pub struct EgressProxy {
    /// Allowlisted mirrors that can always be connected to
    pub allowlisted_mirrors: Vec<String>,
    registry: std::sync::Arc<ScopedTunnelRegistry>,
    audit_store: std::sync::Arc<AuditMmrStore>,
}

impl EgressProxy {
    /// Creates a new proxy with allowlisted mirrors
    pub fn new(
        allowlisted_mirrors: Vec<String>,
        registry: std::sync::Arc<ScopedTunnelRegistry>,
        audit_store: std::sync::Arc<AuditMmrStore>,
    ) -> Self {
        Self {
            allowlisted_mirrors,
            registry,
            audit_store,
        }
    }

    /// Evaluates whether a connection to the given hostname should be permitted
    pub fn evaluate_connection(&self, hostname: &str, now_ms: i64) -> Result<(), BackendError> {
        let normalized = iam::normalize_service_authority(hostname).unwrap_or_else(|_| hostname.to_string());

        if self.allowlisted_mirrors.iter().any(|m| m == &normalized) {
            return Ok(());
        }

        if self.registry.is_service_active(&normalized, now_ms) {
            return Ok(());
        }

        let _ = self.audit_store.append_entry(
            0,
            now_ms as u64,
            "spiffe://tantry/egress_proxy",
            "egress",
            "EGRESS_BLOCKED",
            &serde_json::to_string(&serde_json::json!({ "hostname": normalized })).unwrap(),
        );

        Err(BackendError::Execution("EGRESS_BLOCKED".to_string()))
    }
}
