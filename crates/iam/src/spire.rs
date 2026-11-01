use crate::error::IamError;
use crate::svid::WorkloadSvid;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::UnixStream;
use tokio::sync::{RwLock, watch};
use tokio::time::{Duration, sleep};

#[allow(dead_code)]
pub struct SpireSocketIdentityManager {
    socket_path: PathBuf,
    active_svid: Arc<RwLock<Option<WorkloadSvid>>>,
    #[allow(clippy::type_complexity)]
    historical_svids: Arc<RwLock<VecDeque<([u8; 32], Vec<u8>)>>>,
    rotation_watcher: watch::Receiver<()>,
    key_hierarchy: Arc<crate::key_hierarchy::KeyHierarchy>,
}

impl SpireSocketIdentityManager {
    pub async fn connect(
        socket_path: PathBuf,
        key_hierarchy: Arc<crate::key_hierarchy::KeyHierarchy>,
    ) -> Result<Self, IamError> {
        let _stream = tokio::time::timeout(
            Duration::from_millis(500),
            UnixStream::connect(&socket_path),
        )
        .await
        .map_err(|_| IamError::SpireSocketUnavailable("Timeout connecting to socket".to_string()))?
        .map_err(|e| IamError::SpireSocketUnavailable(e.to_string()))?;

        let (tx, rx) = watch::channel(());
        let active_svid: Arc<RwLock<Option<WorkloadSvid>>> = Arc::new(RwLock::new(None));
        let historical_svids = Arc::new(RwLock::new(VecDeque::with_capacity(16)));

        let active_clone = Arc::clone(&active_svid);
        let history_clone = Arc::clone(&historical_svids);

        tokio::spawn(async move {
            loop {
                let sleep_duration = {
                    let current = active_clone.read().await;
                    if let Some(svid) = &*current {
                        let ttl = svid.expires_at_ms - svid.issued_at_ms;
                        let target = svid.issued_at_ms + (ttl as f64 * 0.8) as i64;
                        let now = chrono::Utc::now().timestamp_millis();

                        if target > now {
                            Duration::from_millis((target - now) as u64)
                        } else {
                            Duration::from_secs(60) // Retry soon if already past rotation threshold
                        }
                    } else {
                        Duration::from_secs(3600)
                    }
                };

                sleep(sleep_duration).await;

                let mut current = active_clone.write().await;
                if let Some(svid) = current.take() {
                    let mut history = history_clone.write().await;
                    if history.len() >= 16 {
                        history.pop_front();
                    }
                    history.push_back((svid.ed25519_pk, svid.mldsa65_pk));
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
        self.active_svid
            .try_read()
            .ok()
            .and_then(|guard| guard.clone())
    }

    fn verify_jwt_svid(&self, _token: &str, _expected_audience: &str) -> Result<(), IamError> {
        // Spire socket implementation not fully provided in spec for verify_jwt_svid, so just NotImplemented or dummy
        Err(IamError::NotImplemented)
    }

    fn key_hierarchy(&self) -> &crate::key_hierarchy::KeyHierarchy {
        &self.key_hierarchy
    }

    fn sign_audit_sth(
        &self,
        tree_size: u64,
        timestamp_ms: i64,
        mmr_root_blake3: &[u8; 32],
    ) -> Result<crate::ca::AuditSthSignature, IamError> {
        let svid = self
            .current_svid()
            .ok_or_else(|| IamError::SpireSocketUnavailable("No active svid".into()))?;
        crate::ca::sign_audit_sth(
            tree_size,
            timestamp_ms,
            *mmr_root_blake3,
            svid.ed25519_seed.as_ref(),
            svid.mldsa65_sk_bytes.as_ref(),
        )
    }

    #[allow(clippy::collapsible_if)]
    fn verify_audit_sth(&self, sth: &crate::ca::AuditSthSignature) -> Result<(), IamError> {
        if let Some(svid) = self.current_svid() {
            if crate::ca::verify_audit_sth(sth, &svid.ed25519_pk, &svid.mldsa65_pk).is_ok() {
                return Ok(());
            }
        }

        let history = if let Ok(guard) = self.historical_svids.try_read() {
            guard.clone()
        } else {
            return Err(IamError::SpireSocketUnavailable("No active svid".into()));
        };

        for (ed_pk, ml_pk) in history.iter().rev() {
            if crate::ca::verify_audit_sth(sth, ed_pk, ml_pk).is_ok() {
                return Ok(());
            }
        }

        Err(IamError::SpireSocketUnavailable("No active svid".into()))
    }
}
