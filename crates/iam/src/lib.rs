pub mod dpop;
pub mod ca;
pub mod error;
pub mod key_hierarchy;
pub mod spire;
pub mod svid;
pub mod tunnel_grant;
pub mod spiffe;
pub mod pq_ext;

pub use ca::*;
pub use error::*;
pub use key_hierarchy::*;
pub use spire::*;
pub use svid::*;
pub use dpop::*;
pub use tunnel_grant::*;

pub trait IdentityManager: Send + Sync {
    fn current_svid(&self) -> Option<WorkloadSvid> { None }
    fn mint_subagent_svid(&self, _parent_svid: &WorkloadSvid, _subagent_name: &str, _child_task_id: &str, _requested_ttl: i64) -> Result<WorkloadSvid, IamError> { Err(IamError::NotImplemented) }
    fn mint_jwt_svid(&self, _audience: &[String], _ttl_secs: i64) -> Result<String, IamError> { Err(IamError::NotImplemented) }
    fn verify_jwt_svid(&self, _token: &str, _expected_audience: &str) -> Result<(), IamError> { Err(IamError::NotImplemented) }
    fn mint_dpop_proof(&self, _htm: &str, _htu: &str, _access_token: Option<&str>) -> Result<String, IamError> { Err(IamError::NotImplemented) }
    fn verify_dpop_proof(&self, _proof: &str, _htm: &str, _htu: &str, _access_token: Option<&str>) -> Result<(), IamError> { Err(IamError::NotImplemented) }
    fn request_scoped_tunnel_token(&self, _service_name: &str, _ttl_secs: i64) -> Result<ScopedTunnelGrant, IamError> { Err(IamError::NotImplemented) }
    fn verify_scoped_tunnel_token(&self, _token: &str) -> Result<ScopedTunnelGrant, IamError> { Err(IamError::NotImplemented) }
    fn is_service_tunnel_active(&self, _host_or_authority: &str) -> bool { false }

    fn key_hierarchy(&self) -> &key_hierarchy::KeyHierarchy;
    fn sign_audit_sth(&self, tree_size: u64, timestamp_ms: i64, mmr_root_blake3: &[u8; 32]) -> Result<AuditSthSignature, error::IamError>;
    fn verify_audit_sth(&self, sth: &AuditSthSignature) -> Result<(), error::IamError>;
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct WorkloadIdentitySlot {
    pub spiffe_id_uri: String,
    pub trust_domain: String,
    pub expires_at_ms: i64,
    pub traceparent: Option<String>,
}

impl base::typemap::StateSlot for WorkloadIdentitySlot {
    const WIRE_KEY: &'static str = "tantry.iam.workload_identity";
    const VISIBILITY: base::typemap::SlotVisibility = base::typemap::SlotVisibility::Shared;
    const CODEC_TAG: base::typemap::CodecTag = base::typemap::CodecTag::MessagePackNamed;

    fn encode_payload(&self) -> Result<Vec<u8>, base::error::ExtensionError> {
        rmp_serde::to_vec_named(self).map_err(|e| base::error::ExtensionError::SerializationFailed(e.to_string()))
    }

    fn decode_payload(bytes: &[u8]) -> Result<Self, base::error::ExtensionError> {
        rmp_serde::from_slice(bytes).map_err(|e| base::error::ExtensionError::DeserializationFailed(e.to_string()))
    }
}

pub enum DualModeInner {
    Spire(SpireSocketIdentityManager),
    Sovereign(SovereignCaIdentityManager),
}

pub struct DualModeIdentityProvider {
    pub inner: DualModeInner,
    pub registry: std::sync::Arc<ScopedTunnelRegistry>,
}

impl DualModeIdentityProvider {
    pub async fn new(
        spire_socket_path: std::path::PathBuf,
        enable_embedded_sovereign_ca_fallback: bool,
        master_key: zeroize::Zeroizing<[u8; 32]>,
        data_dir: &std::path::Path,
    ) -> Result<Self, IamError> {
        let mut master_key_arr = [0u8; 32];
        master_key_arr.copy_from_slice(master_key.as_ref());
        let key_hierarchy = std::sync::Arc::new(crate::key_hierarchy::KeyHierarchy::new(master_key_arr));

        let inner = match SpireSocketIdentityManager::connect(spire_socket_path, key_hierarchy.clone()).await {
            Ok(spire) => DualModeInner::Spire(spire),
            Err(_) if enable_embedded_sovereign_ca_fallback => {
                let ca = SovereignCaIdentityManager::new(master_key, data_dir)?;
                DualModeInner::Sovereign(ca)
            }
            Err(e) => return Err(e),
        };

        Ok(Self {
            inner,
            registry: std::sync::Arc::new(ScopedTunnelRegistry::new()),
        })
    }
}

impl IdentityManager for DualModeIdentityProvider {
    fn current_svid(&self) -> Option<WorkloadSvid> {
        match &self.inner {
            DualModeInner::Spire(s) => s.current_svid(),
            DualModeInner::Sovereign(s) => s.current_svid(),
        }
    }

    fn request_scoped_tunnel_token(&self, service_name: &str, ttl_secs: i64) -> Result<ScopedTunnelGrant, IamError> {
        let svid = self.current_svid().ok_or_else(|| IamError::SpireSocketUnavailable("No active svid".into()))?;
        self.registry.issue_grant(ttl_secs, &ScopedTunnelRegistry::normalize_host(service_name), &svid)
    }

    fn verify_scoped_tunnel_token(&self, token: &str) -> Result<ScopedTunnelGrant, IamError> {
        self.registry.verify_token(token, self, chrono::Utc::now().timestamp_millis())
    }

    fn is_service_tunnel_active(&self, host_or_authority: &str) -> bool {
        self.registry.is_service_active(host_or_authority, chrono::Utc::now().timestamp_millis())
    }

    fn key_hierarchy(&self) -> &crate::key_hierarchy::KeyHierarchy {
        match &self.inner {
            DualModeInner::Spire(s) => s.key_hierarchy(),
            DualModeInner::Sovereign(s) => s.key_hierarchy(),
        }
    }

    fn sign_audit_sth(&self, tree_size: u64, timestamp_ms: i64, mmr_root_blake3: &[u8; 32]) -> Result<AuditSthSignature, IamError> {
        match &self.inner {
            DualModeInner::Spire(s) => s.sign_audit_sth(tree_size, timestamp_ms, mmr_root_blake3),
            DualModeInner::Sovereign(s) => s.sign_audit_sth(tree_size, timestamp_ms, mmr_root_blake3),
        }
    }

    fn verify_audit_sth(&self, sth: &AuditSthSignature) -> Result<(), IamError> {
        match &self.inner {
            DualModeInner::Spire(s) => s.verify_audit_sth(sth),
            DualModeInner::Sovereign(s) => s.verify_audit_sth(sth),
        }
    }
}
