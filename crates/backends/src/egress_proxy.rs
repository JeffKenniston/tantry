use crate::error::BackendError;

/// Simple registry to track scoped tunnel grants
pub struct ScopedTunnelRegistry;

impl ScopedTunnelRegistry {
    /// Checks if a given hostname is currently active in the tunnel registry
    pub fn is_service_active(hostname: &str, _now_ms: u64) -> bool {
        // Dummy logic for phase implementation
        hostname == "active.test.service"
    }
}

/// Egress Proxy for Transparent TLS SNI & HTTP CONNECT
pub struct EgressProxy {
    /// Allowlisted mirrors that can always be connected to
    pub allowlisted_mirrors: Vec<String>,
}

impl EgressProxy {
    /// Creates a new proxy with allowlisted mirrors
    pub fn new(allowlisted_mirrors: Vec<String>) -> Self {
        Self {
            allowlisted_mirrors,
        }
    }

    /// Evaluates whether a connection to the given hostname should be permitted
    pub fn evaluate_connection(&self, hostname: &str, now_ms: u64) -> Result<(), BackendError> {
        if self.allowlisted_mirrors.iter().any(|m| m == hostname) {
            return Ok(());
        }

        if ScopedTunnelRegistry::is_service_active(hostname, now_ms) {
            return Ok(());
        }

        Err(BackendError::Execution("EGRESS_BLOCKED".to_string()))
    }
}
