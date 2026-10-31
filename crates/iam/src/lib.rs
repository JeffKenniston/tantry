pub mod ca;
pub mod dpop;
pub mod error;
pub mod key_hierarchy;
pub mod pq_ext;
pub mod spiffe;
pub mod spire;
pub mod svid;
pub mod tunnel_grant;

pub use ca::*;
pub use dpop::*;
pub use error::*;
pub use key_hierarchy::*;
pub use spire::*;
pub use svid::*;
pub use tunnel_grant::*;

use base::error::ExtensionError;
#[allow(unused_imports)]
use base::path::PosixPath;

use base::typemap::{CodecTag, SlotVisibility, StateSlot};

pub trait IdentityManager: Send + Sync {
    fn current_svid(&self) -> Option<WorkloadSvid> {
        None
    }
    fn mint_subagent_svid(
        &self,
        parent_svid: &WorkloadSvid,
        subagent_name: &str,
        child_task_id: &str,
        requested_ttl: i64,
    ) -> Result<WorkloadSvid, IamError> {
        let child_spiffe = parent_svid
            .spiffe_id
            .derive_subagent(subagent_name, child_task_id)?;
        let mut new_svid = parent_svid.clone();
        new_svid.spiffe_id = child_spiffe;
        let requested_exp = chrono::Utc::now() + chrono::Duration::seconds(requested_ttl);
        new_svid.expires_at_ms = if requested_exp.timestamp_millis() < parent_svid.expires_at_ms {
            requested_exp.timestamp_millis()
        } else {
            parent_svid.expires_at_ms
        };
        Ok(new_svid)
    }
    fn mint_jwt_svid(&self, audience: &[String], ttl_secs: i64) -> Result<String, IamError> {
        use base64::Engine;
        let svid = self
            .current_svid()
            .ok_or_else(|| IamError::SpireSocketUnavailable("No active svid".into()))?;
        let now = chrono::Utc::now().timestamp();
        let exp = now + ttl_secs;
        let claims = JwtSvidClaims {
            iss: svid.spiffe_id.uri().to_string(),
            sub: svid.spiffe_id.uri().to_string(),
            aud: audience.to_vec(),
            exp,
            iat: now,
            jti: uuid::Uuid::now_v7().to_string(),
            pq_pk_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&svid.mldsa65_pk),
            htm: None,
            htu: None,
        };
        crate::svid::mint_hybrid_jwt_svid(&svid, &claims)
    }
    fn verify_jwt_svid(&self, _token: &str, _expected_audience: &str) -> Result<(), IamError> {
        Err(IamError::NotImplemented)
    }
    fn mint_dpop_proof(
        &self,
        htm: &str,
        htu: &str,
        access_token: Option<&str>,
    ) -> Result<String, IamError> {
        let svid = self
            .current_svid()
            .ok_or_else(|| IamError::SpireSocketUnavailable("No active svid".into()))?;
        let mut seed = [0u8; 32];
        seed.copy_from_slice(svid.ed25519_seed.as_ref());
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        crate::dpop::mint_dpop_proof(
            &signing_key,
            htm,
            htu,
            access_token,
            chrono::Utc::now().timestamp(),
        )
    }
    fn verify_dpop_proof(
        &self,
        _proof: &str,
        _htm: &str,
        _htu: &str,
        _access_token: Option<&str>,
        _replay_cache: &dashmap::DashMap<String, i64>,
    ) -> Result<(), IamError> {
        Err(IamError::NotImplemented)
    }
    fn request_scoped_tunnel_token(
        &self,
        _service_name: &str,
        _ttl_secs: i64,
    ) -> Result<ScopedTunnelGrant, IamError> {
        Err(IamError::NotImplemented)
    }
    fn verify_scoped_tunnel_token(&self, _token: &str) -> Result<ScopedTunnelGrant, IamError> {
        Err(IamError::NotImplemented)
    }
    fn is_service_tunnel_active(&self, _host_or_authority: &str) -> bool {
        false
    }

    fn key_hierarchy(&self) -> &key_hierarchy::KeyHierarchy;
    fn sign_audit_sth(
        &self,
        tree_size: u64,
        timestamp_ms: i64,
        mmr_root_blake3: &[u8; 32],
    ) -> Result<AuditSthSignature, error::IamError>;
    fn verify_audit_sth(&self, sth: &AuditSthSignature) -> Result<(), error::IamError>;
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct WorkloadIdentitySlot {
    pub spiffe_id_uri: String,
    pub trust_domain: String,
    pub expires_at_ms: i64,
    pub traceparent: Option<String>,
}

impl StateSlot for WorkloadIdentitySlot {
    const WIRE_KEY: &'static str = "tantry.iam.workload_identity";
    const VISIBILITY: SlotVisibility = SlotVisibility::Shared;
    const CODEC_TAG: CodecTag = CodecTag::MessagePackNamed;

    fn encode_payload(&self) -> Result<Vec<u8>, ExtensionError> {
        rmp_serde::to_vec_named(self)
            .map_err(|e| ExtensionError::SerializationFailed(e.to_string()))
    }

    fn decode_payload(bytes: &[u8]) -> Result<Self, ExtensionError> {
        rmp_serde::from_slice(bytes)
            .map_err(|e| ExtensionError::DeserializationFailed(e.to_string()))
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
        let key_hierarchy =
            std::sync::Arc::new(crate::key_hierarchy::KeyHierarchy::new(master_key_arr));

        let inner =
            match SpireSocketIdentityManager::connect(spire_socket_path, key_hierarchy.clone())
                .await
            {
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

    fn request_scoped_tunnel_token(
        &self,
        service_name: &str,
        ttl_secs: i64,
    ) -> Result<ScopedTunnelGrant, IamError> {
        let svid = self
            .current_svid()
            .ok_or_else(|| IamError::SpireSocketUnavailable("No active svid".into()))?;
        self.registry.issue_grant(
            ttl_secs,
            &ScopedTunnelRegistry::normalize_host(service_name),
            &svid,
        )
    }

    fn verify_scoped_tunnel_token(&self, token: &str) -> Result<ScopedTunnelGrant, IamError> {
        self.registry
            .verify_token(token, self, chrono::Utc::now().timestamp_millis())
    }

    fn is_service_tunnel_active(&self, host_or_authority: &str) -> bool {
        self.registry
            .is_service_active(host_or_authority, chrono::Utc::now().timestamp_millis())
    }

    fn verify_jwt_svid(&self, token: &str, expected_audience: &str) -> Result<(), IamError> {
        match &self.inner {
            DualModeInner::Spire(s) => s.verify_jwt_svid(token, expected_audience),
            DualModeInner::Sovereign(s) => s.verify_jwt_svid(token, expected_audience),
        }
    }

    fn key_hierarchy(&self) -> &crate::key_hierarchy::KeyHierarchy {
        match &self.inner {
            DualModeInner::Spire(s) => s.key_hierarchy(),
            DualModeInner::Sovereign(s) => s.key_hierarchy(),
        }
    }

    fn sign_audit_sth(
        &self,
        tree_size: u64,
        timestamp_ms: i64,
        mmr_root_blake3: &[u8; 32],
    ) -> Result<AuditSthSignature, IamError> {
        match &self.inner {
            DualModeInner::Spire(s) => s.sign_audit_sth(tree_size, timestamp_ms, mmr_root_blake3),
            DualModeInner::Sovereign(s) => {
                s.sign_audit_sth(tree_size, timestamp_ms, mmr_root_blake3)
            }
        }
    }

    fn verify_audit_sth(&self, sth: &AuditSthSignature) -> Result<(), IamError> {
        match &self.inner {
            DualModeInner::Spire(s) => s.verify_audit_sth(sth),
            DualModeInner::Sovereign(s) => s.verify_audit_sth(sth),
        }
    }
}
