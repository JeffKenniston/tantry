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
