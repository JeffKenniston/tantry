use std::sync::Arc;
use tokio::net::UnixStream;
use tokio::sync::watch;
use std::collections::VecDeque;
use std::sync::RwLock;
use crate::error::IamError;
use crate::svid::WorkloadSvid;
use crate::IdentityManager;
use crate::key_hierarchy::KeyHierarchy;
use crate::tunnel_grant::ScopedTunnelRegistry;
use crate::ca::SovereignCaIdentityManager;
use tokio::time::Duration;

pub struct SpireSocketIdentityManager {
    pub socket_path: String,
    pub svid_rx: watch::Receiver<Option<Arc<WorkloadSvid>>>,
    pub historical_keys: Arc<RwLock<VecDeque<(Arc<WorkloadSvid>, i64)>>>, // (svid, expires_at)
    pub registry: Arc<ScopedTunnelRegistry>,
    pub keys: Arc<KeyHierarchy>,
}

impl SpireSocketIdentityManager {
    pub async fn connect(path: &str, registry: Arc<ScopedTunnelRegistry>, keys: Arc<KeyHierarchy>) -> Result<Self, IamError> {
        // Attempt Unix socket connect
        let _stream = UnixStream::connect(path).await
            .map_err(|_| IamError::SpireSocketUnavailable(path.to_string()))?;

        let (_tx, rx) = watch::channel(None);
        let historical_keys = Arc::new(RwLock::new(VecDeque::with_capacity(16)));
        let _hist_clone = historical_keys.clone();
        let _path_clone = path.to_string();

        // Spawn a background task to fetch and rotate SVIDs
        tokio::spawn(async move {
            loop {
                use chrono::{Utc, Duration};
                use crate::spiffe::SpiffeId;
                use ed25519_dalek::SigningKey;


                use getrandom::fill;

                // 1. Fetch SPIRE X.509/JWT credentials (Mocked for now)
                let mut ed_seed = [0u8; 32];
                fill(&mut ed_seed).unwrap();
                let ed_sk = SigningKey::from_bytes(&ed_seed);
                let ed_pk = ed_sk.verifying_key();
                let pkcs8_der = pkcs8::EncodePrivateKey::to_pkcs8_der(&ed_sk).unwrap().as_bytes().to_vec();

                // 2. Generate local ML-DSA-65 overlay keypair


                                                let mut mldsa_seed = [0u8; 32];
                fill(&mut mldsa_seed).unwrap();
                let seed_array: ml_dsa::Seed = mldsa_seed.into();
                let sk = ml_dsa::ExpandedSigningKey::<ml_dsa::MlDsa65>::from_seed(&seed_array);

                // Use .encode() based on examining `verifying.rs`
                let pk = sk.verifying_key();
                let pk_encoded = pk.encode();
                let mldsa_pk_bytes = pk_encoded.as_slice().to_vec();

                #[allow(deprecated)]
                let sk_encoded = sk.to_expanded();
                let mldsa_sk_bytes = sk_encoded.as_slice().to_vec();

                let now = Utc::now();
                let ttl_secs = 3600; // 1 hour TTL from SPIRE
                let expires = now + Duration::seconds(ttl_secs);

                let svid = Arc::new(WorkloadSvid {
                    spiffe_id: SpiffeId::parse("spiffe://example.org/workload").unwrap(),
                    cert_der_chain: vec![],
                    ed25519_pkcs8_der: zeroize::Zeroizing::new(pkcs8_der),
                    ed25519_public_key: ed_pk.to_bytes(),
                    mldsa65_signing_key_bytes: zeroize::Zeroizing::new(mldsa_sk_bytes),
                    mldsa65_verifying_key_bytes: mldsa_pk_bytes,
                    issued_at: now,
                    expires_at: expires,
                });

                // 3. Push to watch channel
                let _ = _tx.send(Some(svid.clone()));

                // 4. Add to historical_keys bounded ring buffer (max 16)
                {
                    let mut hist = _hist_clone.write().unwrap();
                    if hist.len() >= 16 {
                        hist.pop_back();
                    }
                    hist.push_front((svid, expires.timestamp_millis()));
                }

                // 5. Sleep for 80% of TTL
                let sleep_secs = (ttl_secs as f64 * 0.8) as u64;
                tokio::time::sleep(tokio::time::Duration::from_secs(sleep_secs)).await;
            }
        });

        Ok(Self {
            socket_path: path.to_string(),
            svid_rx: rx,
            historical_keys,
            registry,
            keys,
        })
    }
}

pub struct DualModeIdentityProvider {
    pub primary: Option<SpireSocketIdentityManager>,
    pub fallback: Option<SovereignCaIdentityManager>,
    pub registry: Arc<ScopedTunnelRegistry>,
    pub keys: Arc<KeyHierarchy>,
}

impl DualModeIdentityProvider {
    pub async fn new(
        spire_socket_path: &str,
        enable_fallback: bool,
    ) -> Self {
        let registry = Arc::new(ScopedTunnelRegistry::new());
        let keys = Arc::new(KeyHierarchy::new());

        let primary = match tokio::time::timeout(
            Duration::from_millis(500),
            SpireSocketIdentityManager::connect(spire_socket_path, registry.clone(), keys.clone())
        ).await {
            Ok(Ok(pm)) => Some(pm),
            _ => None,
        };

        let fallback = if primary.is_none() && enable_fallback {
            Some(SovereignCaIdentityManager::new(registry.clone(), keys.clone()))
        } else {
            None
        };

        Self {
            primary,
            fallback,
            registry,
            keys,
        }
    }
}

impl IdentityManager for SpireSocketIdentityManager {
    fn current_svid(&self) -> Option<Arc<WorkloadSvid>> {
        self.svid_rx.borrow().clone()
    }

    fn key_hierarchy(&self) -> Arc<KeyHierarchy> {
        self.keys.clone()
    }
}

impl IdentityManager for DualModeIdentityProvider {
    fn current_svid(&self) -> Option<Arc<WorkloadSvid>> {
        if let Some(primary) = &self.primary {
            if let Some(svid) = primary.current_svid() {
                return Some(svid);
            }
        }
        if let Some(fallback) = &self.fallback {
            return fallback.current_svid();
        }
        None
    }

    fn key_hierarchy(&self) -> Arc<KeyHierarchy> {
        self.keys.clone()
    }
}
