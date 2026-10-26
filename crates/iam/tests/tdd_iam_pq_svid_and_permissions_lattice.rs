use chrono::Utc;
use iam::IdentityManager;
use iam::ca::{SovereignCaIdentityManager, acquire_or_init_master_key};
use iam::error::IamError;
use iam::key_hierarchy::KeyHierarchy;
use iam::svid::WorkloadSvid;
use iam::tunnel_grant::ScopedTunnelRegistry;
use ml_dsa::MlDsa65;
use ml_dsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
use ml_dsa::signature::Keypair;
use rand::RngCore;

fn mint_dummy_svid_for_test(spiffe_id_str: &str) -> WorkloadSvid {
    let mut secret = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut secret);
    let ed_sk = ed25519_dalek::SigningKey::from_bytes(&secret);
    let ed_pub = ed_sk.verifying_key().to_bytes();
    let mut ed_pkcs8 = vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    ed_pkcs8.extend_from_slice(&secret);

    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    let ml_sk = ml_dsa::SigningKey::<MlDsa65>::from_seed((&seed).into());
    let ml_pk = ml_sk.verifying_key();
    let ml_pkcs8 = ml_sk.to_pkcs8_der().unwrap().as_bytes().to_vec();
    let ml_spki = ml_pk.to_public_key_der().unwrap().as_bytes().to_vec();

    let now = chrono::Utc::now();
    WorkloadSvid {
        spiffe_id: iam::spiffe::SpiffeId::parse(spiffe_id_str).unwrap(),
        cert_der_chain: vec![],
        ed25519_pkcs8_der: zeroize::Zeroizing::new(ed_pkcs8),
        ed25519_public_key: ed_pub,
        mldsa65_signing_key_bytes: zeroize::Zeroizing::new(ml_pkcs8),
        mldsa65_verifying_key_bytes: ml_spki,
        issued_at: now - chrono::Duration::seconds(3600),
        expires_at: now + chrono::Duration::seconds(3600),
    }
}

#[test]
fn test_spiffe_id_subagent_ttl_narrowing() {
    let temp = tempfile::tempdir().unwrap();
    let db_dir = temp.path().to_path_buf();
    let root_kek = acquire_or_init_master_key(&db_dir).unwrap();
    let ca = SovereignCaIdentityManager::new(root_kek.clone(), &db_dir).unwrap();

    // In SovereignCaIdentityManager, current_svid() is None, so we create a dummy parent svid
    let parent_svid = mint_dummy_svid_for_test("spiffe://example.org/agent/agent1/task/task1");

    // Narrowing TTL: request more than parent's expiry -> gets clamped to parent's expiry
    let child1 = ca
        .mint_subagent_svid(&parent_svid, "sub1", "task2", 7200)
        .unwrap();
    assert_eq!(child1.expires_at, parent_svid.expires_at);
    assert_eq!(
        child1.spiffe_id.uri(),
        "spiffe://example.org/agent/agent1/task/task1/subagent/sub1/task/task2"
    );

    // Narrowing TTL: request less than parent's expiry -> gets exactly the requested expiry
    let child2 = ca
        .mint_subagent_svid(&parent_svid, "sub1", "task2", 1800)
        .unwrap();
    assert!(child2.expires_at < parent_svid.expires_at);
}

#[tokio::test]
async fn test_sovereign_ca_and_audits_extended() {
    let temp = tempfile::tempdir().unwrap();
    let db_dir = temp.path().to_path_buf();
    let root_kek = acquire_or_init_master_key(&db_dir).unwrap();
    let ca = SovereignCaIdentityManager::new(root_kek.clone(), &db_dir).unwrap();

    // Test STH Dual Verification
    let mmr_root = [42u8; 32];
    let sth = ca.sign_audit_sth(10, 1000, &mmr_root).unwrap();

    // Should verify successfully
    assert!(ca.verify_audit_sth(&sth).is_ok());

    // Tamper with tree_size
    let mut tampered_sth = sth.clone();
    tampered_sth.tree_size = 11;
    assert!(ca.verify_audit_sth(&tampered_sth).is_err());
}

#[test]
fn test_dpop_proof_verification_and_replay_rejection() {
    let temp = tempfile::tempdir().unwrap();
    let db_dir = temp.path().to_path_buf();
    let root_kek = acquire_or_init_master_key(&db_dir).unwrap();
    let _ca = SovereignCaIdentityManager::new(root_kek.clone(), &db_dir).unwrap();

    let svid = mint_dummy_svid_for_test("spiffe://example.org/agent/agent1/task/task1");

    let proof = iam::dpop::mint_dpop_proof(
        &svid,
        "POST",
        "https://api.example.com/data?query=1",
        Some("token123"),
    )
    .unwrap();

    let cache = dashmap::DashMap::new();
    // Verify proof works
    assert!(
        iam::dpop::verify_dpop_proof(
            &proof,
            "POST",
            "https://api.example.com/data",
            Some("token123"),
            &cache
        )
        .is_ok()
    );

    // Replay attack should fail
    assert!(
        iam::dpop::verify_dpop_proof(
            &proof,
            "POST",
            "https://api.example.com/data",
            Some("token123"),
            &cache
        )
        .is_err()
    );

    // Tampered HTM should fail
    let proof2 = iam::dpop::mint_dpop_proof(
        &svid,
        "GET",
        "https://api.example.com/data",
        Some("token123"),
    )
    .unwrap();
    assert!(
        iam::dpop::verify_dpop_proof(
            &proof2,
            "POST",
            "https://api.example.com/data",
            Some("token123"),
            &cache
        )
        .is_err()
    );
}

#[tokio::test]
async fn test_scoped_tunnel_registry_host_matching() {
    let temp = tempfile::tempdir().unwrap();
    let db_dir = temp.path().to_path_buf();
    let root_kek = acquire_or_init_master_key(&db_dir).unwrap();
    let _ca = SovereignCaIdentityManager::new(root_kek.clone(), &db_dir).unwrap();

    let svid = mint_dummy_svid_for_test("spiffe://example.org/agent/agent1/task/task1");

    let registry = ScopedTunnelRegistry::new();
    let grant = registry.issue_grant(3600, "api.stripe.com", &svid).unwrap();

    // Test normalization
    assert_eq!(
        ScopedTunnelRegistry::normalize_host("https://api.stripe.com:443"),
        "api.stripe.com"
    );
    assert!(
        registry.is_service_active("https://api.stripe.com:443", Utc::now().timestamp_millis())
    );

    struct DummyVerifier {
        svid: WorkloadSvid,
    }
    impl IdentityManager for DummyVerifier {
        fn current_svid(&self) -> Option<WorkloadSvid> {
            Some(self.svid.clone())
        }
        fn verify_jwt_svid(&self, token: &str, expected_audience: &str) -> Result<(), IamError> {
            iam::svid::verify_hybrid_jwt_svid(
                token,
                expected_audience,
                &self.svid.ed25519_public_key,
                &self.svid.mldsa65_verifying_key_bytes,
                true,
            )
            .map(|_| ())
        }
        fn key_hierarchy(&self) -> &KeyHierarchy {
            unimplemented!()
        }
        fn sign_audit_sth(
            &self,
            _: u64,
            _: i64,
            _: &[u8; 32],
        ) -> Result<iam::ca::AuditSthSignature, IamError> {
            unimplemented!()
        }
        fn verify_audit_sth(&self, _: &iam::ca::AuditSthSignature) -> Result<(), IamError> {
            unimplemented!()
        }
    }

    let verifier = DummyVerifier { svid };

    let verified_grant = registry
        .verify_token(&grant.token, &verifier, Utc::now().timestamp_millis())
        .unwrap();
    assert_eq!(verified_grant.service_name, "api.stripe.com");
}

#[test]
fn test_key_hierarchy() {
    let mut kek = [0u8; 32];
    #[allow(clippy::needless_range_loop)]
    for i in 0..32 {
        kek[i] = i as u8;
    }
    let kh = KeyHierarchy::new(kek);

    let mut epoch_salt = [0u8; 32];
    epoch_salt[0] = 1;
    let mut thread_salt = [0u8; 32];
    thread_salt[0] = 2;

    let _dek = kh
        .derive_dek_from_salts(1, &epoch_salt, "t1", &thread_salt)
        .unwrap();

    kh.crypto_shred_thread("t1");
    let result = kh.derive_dek_from_salts(1, &epoch_salt, "t1", &thread_salt);
    assert!(result.is_err());
}
