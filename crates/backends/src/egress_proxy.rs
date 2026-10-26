use crate::error::BackendError;

// Actual ScopedTunnelRegistry is in iam crate.
// Here we use it.
use iam::tunnel_grant::ScopedTunnelRegistry;

/// Egress Proxy for Transparent TLS SNI & HTTP CONNECT
pub struct EgressProxy {
    /// Allowlisted mirrors that can always be connected to
    pub allowlisted_mirrors: Vec<String>,
    registry: std::sync::Arc<ScopedTunnelRegistry>,
}

impl EgressProxy {
    /// Creates a new proxy with allowlisted mirrors
    pub fn new(
        allowlisted_mirrors: Vec<String>,
        registry: std::sync::Arc<ScopedTunnelRegistry>,
    ) -> Self {
        Self {
            allowlisted_mirrors,
            registry,
        }
    }

    /// Evaluates whether a connection to the given hostname should be permitted
    pub fn evaluate_connection(&self, hostname: &str, now_ms: i64) -> Result<(), BackendError> {
        let normalized = ScopedTunnelRegistry::normalize_host(hostname);

        if self.allowlisted_mirrors.iter().any(|m| m == &normalized) {
            return Ok(());
        }

        if self.registry.is_service_active(&normalized, now_ms) {
            return Ok(());
        }

        Err(BackendError::Execution("EGRESS_BLOCKED".to_string()))
    }
}
