use crate::error::IamError;
use crate::svid::WorkloadSvid;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::UnixStream;
use tokio::sync::{watch, RwLock};
use tokio::time::{sleep, Duration};

#[allow(dead_code)]
pub struct SpireSocketIdentityManager {
    socket_path: PathBuf,
    active_svid: Arc<RwLock<Option<WorkloadSvid>>>,
    historical_svids: Arc<RwLock<VecDeque<WorkloadSvid>>>,
    rotation_watcher: watch::Receiver<()>,
    key_hierarchy: Arc<crate::key_hierarchy::KeyHierarchy>,
}

impl SpireSocketIdentityManager {
    pub async fn connect(socket_path: PathBuf, key_hierarchy: Arc<crate::key_hierarchy::KeyHierarchy>) -> Result<Self, IamError> {
        let _stream = tokio::time::timeout(
            Duration::from_millis(500),
            UnixStream::connect(&socket_path),
        )
        .await
        .map_err(|_| IamError::SpireSocketUnavailable("Timeout connecting to socket".to_string()))?
        .map_err(|e| IamError::SpireSocketUnavailable(e.to_string()))?;

        let (tx, rx) = watch::channel(());
        let active_svid = Arc::new(RwLock::new(None));
        let historical_svids = Arc::new(RwLock::new(VecDeque::with_capacity(16)));

        let active_clone = Arc::clone(&active_svid);
        let history_clone = Arc::clone(&historical_svids);

        tokio::spawn(async move {
            loop {
                sleep(Duration::from_secs(3600)).await;

                let mut current = active_clone.write().await;
                if let Some(svid) = current.take() {
                     let mut history = history_clone.write().await;
                     if history.len() >= 16 {
                          history.pop_front();
                     }
                     history.push_back(svid);
                }

                let _ = tx.send(());
            }
        });

        Ok(Self {
            socket_path,
            active_svid,
            historical_svids,
            rotation_watcher: rx,
            key_hierarchy,
        })
    }
}

impl crate::IdentityManager for SpireSocketIdentityManager {
    fn current_svid(&self) -> Option<WorkloadSvid> {
         self.active_svid.try_read().ok().and_then(|guard| guard.clone())
    }

    fn key_hierarchy(&self) -> &crate::key_hierarchy::KeyHierarchy {
        &self.key_hierarchy
    }

    fn sign_audit_sth(&self, tree_size: u64, timestamp_ms: i64, mmr_root_blake3: &[u8; 32]) -> Result<crate::ca::AuditSthSignature, IamError> {
        let svid = self.current_svid().ok_or_else(|| IamError::SpireSocketUnavailable("No active svid".into()))?;
        crate::ca::sign_audit_sth(tree_size, timestamp_ms, *mmr_root_blake3, svid.ed25519_pkcs8_der.as_ref(), svid.mldsa65_signing_key_bytes.as_ref())
    }

    fn verify_audit_sth(&self, sth: &crate::ca::AuditSthSignature) -> Result<(), IamError> {
        let svid = self.current_svid().ok_or_else(|| IamError::SpireSocketUnavailable("No active svid".into()))?;
        crate::ca::verify_audit_sth(sth, &svid.ed25519_public_key, &svid.mldsa65_verifying_key_bytes)
    }
}
