use crate::error::BackendError;

// Actual ScopedTunnelRegistry is in iam crate.
// Here we use it.
use data::audit_mmr::AuditMmrStore;
use iam::tunnel_grant::ScopedTunnelRegistry;

/// Extracts target host from initial HTTP CONNECT or TLS ClientHello
pub fn extract_target_host_from_initial_bytes(buf: &[u8]) -> Option<String> {
    // Case 1 (HTTP CONNECT)
    if buf.len() > 8 && buf[..8].eq_ignore_ascii_case(b"CONNECT ") {
        if let Some(end) = buf[8..].windows(5).position(|w| w == b" HTTP") {
            let authority = String::from_utf8_lossy(&buf[8..8 + end]);
            let host = authority.split(':').next().unwrap_or(&authority).to_lowercase();
            return Some(host);
        }
    }

    // Case 2 (TLS 1.3 / 1.2 ClientHello SNI 0x0000)
    if buf.len() >= 43 && buf[0] == 0x16 && buf[5] == 0x01 {
        let mut offset = 43;
        if offset + 1 <= buf.len() {
            let session_id_len = buf[offset] as usize;
            offset += 1 + session_id_len;
            if offset + 2 <= buf.len() {
                let cipher_suites_len = u16::from_be_bytes([buf[offset], buf[offset + 1]]) as usize;
                offset += 2 + cipher_suites_len;
                if offset + 1 <= buf.len() {
                    let compression_methods_len = buf[offset] as usize;
                    offset += 1 + compression_methods_len;
                    if offset + 2 <= buf.len() {
                        let extensions_total_len = u16::from_be_bytes([buf[offset], buf[offset + 1]]) as usize;
                        offset += 2;
                        let end_of_exts = offset + extensions_total_len;
                        while offset + 4 <= end_of_exts && offset + 4 <= buf.len() {
                            let ext_type = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
                            let ext_len = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]) as usize;
                            offset += 4;

                            if ext_type == 0x0000 {
                                if offset + 2 <= buf.len() {
                                    let list_len = u16::from_be_bytes([buf[offset], buf[offset + 1]]) as usize;
                                    let mut list_offset = offset + 2;
                                    let list_end = list_offset + list_len;

                                    while list_offset + 3 <= list_end && list_offset + 3 <= buf.len() {
                                        let name_type = buf[list_offset];
                                        let name_len = u16::from_be_bytes([buf[list_offset + 1], buf[list_offset + 2]]) as usize;
                                        list_offset += 3;

                                        if name_type == 0x00 && list_offset + name_len <= buf.len() {
                                            let host = String::from_utf8_lossy(&buf[list_offset..list_offset + name_len]).to_lowercase();
                                            return Some(host);
                                        }
                                        list_offset += name_len;
                                    }
                                }
                                break;
                            }
                            offset += ext_len;
                        }
                    }
                }
            }
        }
    }
    None
}

/// Egress Proxy for Transparent TLS SNI & HTTP CONNECT

pub struct EgressProxyServer {
    pub allowlisted_mirrors: Vec<String>,
    pub tunnel_registry: std::sync::Arc<ScopedTunnelRegistry>,
    pub audit_mmr: std::sync::Arc<AuditMmrStore>,
    pub iam: Option<std::sync::Arc<dyn iam::IdentityManager + Send + Sync>>,
}

impl EgressProxyServer {
    pub fn evaluate_and_audit_host(&self, raw_initial_bytes: &[u8], now_ms: i64) -> Result<String, BackendError> {
        let host = extract_target_host_from_initial_bytes(raw_initial_bytes)
            .ok_or_else(|| BackendError::EgressBlocked { host: "<missing-sni-or-connect-host>".into() })?;

        let allowed = self.allowlisted_mirrors.iter().any(|m| m.eq_ignore_ascii_case(&host) || host.ends_with(&format!(".{}", m.to_ascii_lowercase())))
            || self.tunnel_registry.is_service_active(&host, now_ms);

        if allowed {
            Ok(host)
        } else {
            let event = serde_json::json!({
                "host": host,
                "timestamp_ms": now_ms,
            });
            let _ = self.audit_mmr.append_entry(
                0,
                now_ms as u64,
                "spiffe://tantry/egress_proxy",
                "egress",
                "EGRESS_BLOCKED",
                &serde_json::to_string(&event).unwrap_or_default(),
            );
            Err(BackendError::EgressBlocked { host })
        }
    }
}
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
