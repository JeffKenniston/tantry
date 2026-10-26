pub mod error;
pub mod keys;
pub mod spiffe;
pub mod pq_ext;
pub mod svid;
pub mod dpop;
pub mod tunnel_grant;
pub mod key_hierarchy;

pub use error::*;
pub use keys::*;
pub use spiffe::*;
pub use pq_ext::*;
pub use svid::*;
pub use dpop::*;
pub use tunnel_grant::*;
pub use key_hierarchy::*;
pub mod ca;
pub mod audit_sth;
pub mod spire;

use std::sync::Arc;
use base::typemap::{StateSlot, SlotVisibility, CodecTag};
use base::error::ExtensionError;
use serde::{Serialize, Deserialize};

pub trait IdentityManager: Send + Sync {
    fn current_svid(&self) -> Option<Arc<svid::WorkloadSvid>>;

    fn mint_subagent_svid(
        &self,
        parent_svid: &svid::WorkloadSvid,
        subagent_name: &str,
        child_task_id: &str,
        requested_ttl: i64,
    ) -> Result<Arc<svid::WorkloadSvid>, error::IamError> {
        let child_spiffe = parent_svid.spiffe_id.derive_subagent(subagent_name, child_task_id)?;
        let parent_expires_at = parent_svid.expires_at.timestamp();
        let now = chrono::Utc::now().timestamp();
        let max_ttl = parent_expires_at - now;
        let final_ttl = requested_ttl.min(max_ttl);
        if final_ttl <= 0 {
            return Err(error::IamError::TtlEscalation);
        }

        let new_svid = svid::WorkloadSvid {
            spiffe_id: child_spiffe,
            cert_der_chain: parent_svid.cert_der_chain.clone(),
            ed25519_pkcs8_der: parent_svid.ed25519_pkcs8_der.clone(),
            ed25519_public_key: parent_svid.ed25519_public_key,
            mldsa65_signing_key_bytes: parent_svid.mldsa65_signing_key_bytes.clone(),
            mldsa65_verifying_key_bytes: parent_svid.mldsa65_verifying_key_bytes.clone(),
            issued_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::seconds(final_ttl),
        };
        Ok(Arc::new(new_svid))
    }

    fn mint_jwt_svid(&self, audience: Vec<String>, _ttl_secs: i64) -> Result<String, error::IamError> {
        if let Some(svid) = self.current_svid() {
            svid::mint_hybrid_jwt_svid(&svid, audience)
        } else {
            Err(error::IamError::MasterKeyUnavailable)
        }
    }

    fn verify_jwt_svid(&self, _token: &str, _expected_audience: &str) -> Result<svid::JwtSvidClaims, error::IamError> {
        Err(error::IamError::CertificateGenerationError("NotImplemented".to_string()))
    }

    fn mint_dpop_proof(&self, htm: &str, htu: &str, access_token: &str) -> Result<String, error::IamError> {
        if let Some(svid) = self.current_svid() {
            dpop::mint_dpop_proof(&svid, htm, htu, Some(access_token))
        } else {
            Err(error::IamError::MasterKeyUnavailable)
        }
    }

    fn verify_dpop_proof(&self, _proof: &str, _htm: &str, _htu: &str, _access_token: &str) -> Result<(), error::IamError> {
        Err(error::IamError::CertificateGenerationError("NotImplemented".to_string()))
    }

    fn request_scoped_tunnel_token(&self, _service_name: &str, _ttl_secs: i64) -> Result<Arc<tunnel_grant::ScopedTunnelGrant>, error::IamError> {
        Err(error::IamError::CertificateGenerationError("NotImplemented".to_string()))
    }

    fn verify_scoped_tunnel_token(&self, _token: &str) -> Result<Arc<tunnel_grant::ScopedTunnelGrant>, error::IamError> {
        Err(error::IamError::CertificateGenerationError("NotImplemented".to_string()))
    }

    fn is_service_tunnel_active(&self, _host_or_authority: &str) -> bool {
        false
    }

    fn sign_audit_sth(&self, tree_size: u64, timestamp_ms: i64, mmr_root_blake3: &[u8; 32]) -> Result<audit_sth::AuditSthSignature, error::IamError> {
        if let Some(svid) = self.current_svid() {
            audit_sth::sign_audit_sth(&svid, tree_size, timestamp_ms, mmr_root_blake3)
        } else {
            Err(error::IamError::MasterKeyUnavailable)
        }
    }

    fn verify_audit_sth(&self, _sth: &audit_sth::AuditSthSignature) -> Result<(), error::IamError> {
        Err(error::IamError::CertificateGenerationError("NotImplemented".to_string()))
    }

    fn key_hierarchy(&self) -> Arc<key_hierarchy::KeyHierarchy>;
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WorkloadIdentitySlot {
    pub spiffe_id_uri: String,
    pub trust_domain: String,
    pub expires_at_ms: i64,
    pub traceparent: String,
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
